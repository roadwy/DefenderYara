
rule Trojan_Win32_Emotetcrypt_IS_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {3e 74 68 61 77 35 67 2b 78 61 70 5e 6a 46 48 34 6e 55 6c 43 77 69 6a 35 5a 37 7a 78 4d 67 49 72 68 32 6f 2a 5a 61 25 54 66 3f } //1 >thaw5g+xap^jFH4nUlCwij5Z7zxMgIrh2o*Za%Tf?
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}