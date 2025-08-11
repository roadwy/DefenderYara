
rule Trojan_BAT_Taskun_GPPG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 61 28 ?? ?? 00 06 02 11 01 17 58 02 8e 69 5d 91 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}