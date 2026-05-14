
rule Trojan_Win32_Androm_BAM_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 33 d1 00 00 b9 33 d1 00 00 b9 33 d1 00 00 b9 33 d1 00 00 b9 33 d1 00 00 b9 33 d1 00 00 ff 75 ?? b9 33 d1 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAM_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 7c 0d 00 00 b9 7c 0d 00 00 b9 7c 0d 00 00 b9 7c 0d 00 00 b9 7c 0d 00 00 b9 7c 0d 00 00 ff 75 ?? b9 7c 0d 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAM_MTB_3{
	meta:
		description = "Trojan:Win32/Androm.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 5c 11 00 00 b9 5c 11 00 00 b9 5c 11 00 00 b9 5c 11 00 00 b9 5c 11 00 00 b9 5c 11 00 00 ff 75 ?? b9 5c 11 00 00 ff 75 ?? b9 5c 11 00 00 ff 75 ?? b9 5c 11 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}