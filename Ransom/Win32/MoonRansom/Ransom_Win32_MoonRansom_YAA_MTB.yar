
rule Ransom_Win32_MoonRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/MoonRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8a 04 30 30 04 1f ff 46 40 47 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}