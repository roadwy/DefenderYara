
rule Backdoor_Win32_Littlemetp_AA_MTB{
	meta:
		description = "Backdoor:Win32/Littlemetp.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? 6a 00 e8 [0-04] 8b 5d ?? 2b d8 6a 00 e8 [0-04] 2b d8 8b 45 ?? 31 18 83 45 [0-02] 83 45 [0-02] 8b 45 ?? 3b 45 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}