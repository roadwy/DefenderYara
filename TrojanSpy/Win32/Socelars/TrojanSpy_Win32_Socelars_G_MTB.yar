
rule TrojanSpy_Win32_Socelars_G_MTB{
	meta:
		description = "TrojanSpy:Win32/Socelars.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0d 00 00 "
		
	strings :
		$a_80_0 = {6d 75 74 65 78 20 64 65 74 65 63 74 65 64 } //mutex detected  10
		$a_80_1 = {45 78 70 6c 6f 72 65 22 3a 22 25 6c 73 22 2c 22 45 6e 63 6f 64 65 22 3a 22 25 6c 73 22 2c 22 63 55 73 65 72 49 64 22 3a 22 25 6c 73 22 2c 22 4c 6f 67 69 6e 4e 61 6d 65 22 3a 22 25 6c 73 22 2c 22 50 73 77 22 3a } //Explore":"%ls","Encode":"%ls","cUserId":"%ls","LoginName":"%ls","Psw":  10
		$a_80_2 = {77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 70 61 79 6d 65 6e 74 73 2f 73 65 74 74 69 6e 67 73 2f 70 61 79 6d 65 6e 74 5f 6d 65 74 68 6f 64 73 2f } //www.facebook.com/payments/settings/payment_methods/  1
		$a_80_3 = {73 65 63 75 72 65 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 61 64 73 2f 6d 61 6e 61 67 65 72 2f 61 63 63 6f 75 6e 74 5f 73 65 74 74 69 6e 67 73 2f 61 63 63 6f 75 6e 74 5f 62 69 6c 6c 69 6e 67 2f } //secure.facebook.com/ads/manager/account_settings/account_billing/  1
		$a_80_4 = {66 72 6f 6d 20 6c 6f 67 69 6e 73 20 77 68 65 72 65 20 62 6c 61 63 6b 6c 69 73 74 65 64 5f 62 79 5f 75 73 65 72 3d 30 20 61 6e 64 20 70 72 65 66 65 72 72 65 64 3d 31 20 61 6e 64 20 20 6f 72 69 67 69 6e 5f 75 72 6c 20 6c 69 6b 65 } //from logins where blacklisted_by_user=0 and preferred=1 and  origin_url like  1
		$a_80_5 = {73 65 6c 65 63 74 20 68 6f 73 74 5f 6b 65 79 2c 6e 61 6d 65 2c 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 2c 65 78 70 69 72 65 73 5f 75 74 63 20 66 72 6f 6d 20 63 6f 6f 6b 69 65 73 20 77 68 65 72 65 20 20 68 6f 73 74 5f 6b 65 79 20 6c 69 6b 65 } //select host_key,name,encrypted_value,expires_utc from cookies where  host_key like  1
		$a_80_6 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //\Google\Chrome\User Data\Default\Login Data  1
		$a_80_7 = {22 43 6f 6f 6b 69 65 22 3a } //"Cookie":  1
		$a_80_8 = {22 4c 6f 67 69 6e 4e 61 6d 65 22 3a } //"LoginName":  1
		$a_80_9 = {22 42 61 6c 61 6e 63 65 22 3a } //"Balance":  1
		$a_80_10 = {22 50 73 77 22 3a } //"Psw":  1
		$a_80_11 = {22 50 61 79 70 61 6c 22 3a } //"Paypal":  1
		$a_80_12 = {22 43 72 65 64 69 74 43 61 72 64 22 3a } //"CreditCard":  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=30
 
}