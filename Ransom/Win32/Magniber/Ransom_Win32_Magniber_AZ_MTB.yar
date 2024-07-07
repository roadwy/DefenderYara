
rule Ransom_Win32_Magniber_AZ_MTB{
	meta:
		description = "Ransom:Win32/Magniber.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {41 8a 08 41 ba fe 00 00 00 32 cb 80 c3 ff 88 0a 48 ff c2 84 db 0f b6 cb 41 0f 44 ca 49 ff c0 8a d9 49 ff c9 75 da 48 83 c4 20 5b 48 ff e0 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100) >=101
 
}