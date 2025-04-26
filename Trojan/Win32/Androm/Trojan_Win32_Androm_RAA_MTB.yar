
rule Trojan_Win32_Androm_RAA_MTB{
	meta:
		description = "Trojan:Win32/Androm.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 45 84 89 85 38 ff ff ff 8d 85 34 ff ff ff 50 8d 85 20 ff ff ff 50 8d 85 38 ff ff ff 50 8b 45 08 8b 00 ff 75 08 } //1
		$a_01_1 = {83 a5 60 ff ff ff 00 8b 45 a4 89 85 68 ff ff ff 83 65 a4 00 8b 95 68 ff ff ff 8d 4d a0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}