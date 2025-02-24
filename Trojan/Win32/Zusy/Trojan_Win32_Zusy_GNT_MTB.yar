
rule Trojan_Win32_Zusy_GNT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? a7 4c 00 68 ?? 45 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? ?? ?? 33 d2 8a d4 89 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}