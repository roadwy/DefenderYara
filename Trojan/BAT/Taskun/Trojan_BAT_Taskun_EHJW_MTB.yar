
rule Trojan_BAT_Taskun_EHJW_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EHJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 07 17 58 0b 11 16 1f 0a 5d 2d 1c 11 09 11 16 1f 64 5d 17 9c 11 08 11 16 11 08 8e 69 5d 11 16 ?? ?? ?? ?? ?? 5d d2 9c 11 16 6c 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}