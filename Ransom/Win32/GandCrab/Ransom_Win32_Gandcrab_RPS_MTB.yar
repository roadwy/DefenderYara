
rule Ransom_Win32_Gandcrab_RPS_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 33 c7 45 d4 90 01 04 81 45 d4 90 01 04 81 6d d4 90 01 04 81 6d d4 90 01 04 81 45 d4 90 01 04 81 6d d4 90 01 04 81 6d d4 90 01 04 81 45 d4 90 01 04 81 6d d4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}