
rule Trojan_Win64_DllHijack_WD_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.WD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 fe 10 73 1b 4a 8d 0c 37 e8 ?? ?? ?? ?? 49 33 04 1e 4a 89 84 35 40 04 00 00 49 83 c6 08 eb df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}