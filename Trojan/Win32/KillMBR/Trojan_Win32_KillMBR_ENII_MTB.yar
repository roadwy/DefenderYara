
rule Trojan_Win32_KillMBR_ENII_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.ENII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d0 0f b6 00 89 c2 8b 45 e8 89 d1 31 c1 8b 55 f0 8b 45 f4 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 ec } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}