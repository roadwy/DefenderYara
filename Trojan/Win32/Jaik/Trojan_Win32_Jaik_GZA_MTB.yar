
rule Trojan_Win32_Jaik_GZA_MTB{
	meta:
		description = "Trojan:Win32/Jaik.GZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 03 4c 24 04 8b 6c 24 1c 03 2c 24 8a 11 8a 7d 00 30 fa 88 11 83 44 24 04 02 ff 04 24 8b 1c 24 8b 7c 24 20 4f 39 fb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}