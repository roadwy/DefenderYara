
rule Trojan_BAT_Taskun_ASES_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 07 08 91 28 ?? 00 00 06 08 1f 16 5d 91 61 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}