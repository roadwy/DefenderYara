
rule Ransom_Win32_IncRansom_YAF_MTB{
	meta:
		description = "Ransom:Win32/IncRansom.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 b4 99 be 1e 00 00 00 f7 fe 0f be 92 ?? ?? ?? ?? 33 ca 8b 45 a4 03 45 b4 88 08 eb 8a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}