from rest_framework import serializers
from django.contrib.auth.models import User



from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


class UserSerializer(serializers.ModelSerializer):
   
    
    # class Meta:
    #     model = User
    #     # exclude = [
    #     #     # "password",
    #     #     "last_login",
    #     #     "date_joined",
    #     #     "groups",
    #     #     "user_permissions",
    #     # ]
    #     fields='__all__'
        
        
   
    # def validate(self, attrs):
    #     from django.contrib.auth.password_validation import validate_password # doğrulama fonksiyonu
    #     from django.contrib.auth.hashers import make_password # şifreleme fonksiyonu
    #     password = attrs['password'] # Password al.
    #     validate_password(password) # Validation'dan geçir.
    #     attrs.update(
    #         {
    #             'password': make_password(password) # Password şifrele ve güncelle.
    #         }
    #     )
    #     return super().validate(attrs) # Orjinal methodu çalıştır.



# !-------------------------------------------------------------------



    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        # widgets = {forms.HiddenInput()}
    )

    password2 = serializers.CharField(
        write_only=True,
        required=True,
    )


    class Meta:
        model = User
        # exclude = [
        #     # "password",
        #     "last_login",
        #     "date_joined",
        #     "groups",
        #     "user_permissions",
        # ]
        fields=["email","password","password2","username"]
        
    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data.get('username'),
            email=validated_data.get('email'),
            # first_name=validated_data.get('first_name'),
        )
        user.set_password(validated_data.get('password'))
        user.save()

        return user