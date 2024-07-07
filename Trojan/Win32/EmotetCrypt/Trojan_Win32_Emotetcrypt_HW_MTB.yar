
rule Trojan_Win32_Emotetcrypt_HW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 60 8b 7d 08 8b 75 0c 8b 4d 10 8b 55 14 ac 30 d0 aa c1 ca 08 e2 } //1
		$a_03_1 = {80 3a 00 74 90 01 01 ac 32 02 aa 42 e2 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}