
rule Trojan_BAT_Taskun_SPPX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 6a 5d d4 11 ?? 28 ?? ?? ?? 0a 9c 06 17 6a 58 0a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}