
rule PWS_Win32_Fareit_MW_MTB{
	meta:
		description = "PWS:Win32/Fareit.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 cb 83 c3 ?? 8d 0b c1 c1 ?? d1 c9 6a ?? 8f 02 01 1a 8d 52 ?? 83 ef ?? ?? ?? ?? 8d 1d ?? ?? ?? ?? 8d 9b 90 09 09 00 83 ee ?? 83 c3 ?? c1 cb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}