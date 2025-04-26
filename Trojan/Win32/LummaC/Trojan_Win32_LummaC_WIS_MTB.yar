
rule Trojan_Win32_LummaC_WIS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.WIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f2 83 e2 3b 81 e6 c4 00 00 00 09 d6 89 c2 83 e2 3b 81 ca ?? ?? ?? ?? 83 e0 c4 31 f0 31 d0 34 bb 04 78 88 44 3c ?? 47 83 c1 02 83 ff 22 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}