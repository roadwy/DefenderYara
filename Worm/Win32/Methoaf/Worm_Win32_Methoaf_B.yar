
rule Worm_Win32_Methoaf_B{
	meta:
		description = "Worm:Win32/Methoaf.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 5f 52 ff d6 8d 85 ?? ?? ff ff 6a 6c 50 ff d6 8d 8d ?? ?? ff ff 6a 6f 51 ff d6 8d 95 ?? ?? ff ff 6a 76 52 ff d6 8d 85 ?? ?? ff ff 6a 65 } //1
		$a_03_1 = {6a 5b 8d 4d bc 51 ff 15 ?? ?? ?? ?? 6a 61 8d 55 ac 52 ff 15 ?? ?? ?? ?? 6a 75 8d 45 8c 50 ff 15 ?? ?? ?? ?? 6a 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}