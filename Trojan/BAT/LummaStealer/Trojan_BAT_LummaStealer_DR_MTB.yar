
rule Trojan_BAT_LummaStealer_DR_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 bf 00 00 70 a2 25 17 28 ?? ?? ?? 0a 13 09 12 09 28 ?? ?? ?? 0a a2 25 18 72 c3 00 00 70 a2 25 19 11 07 a2 25 1a 72 db 00 00 70 a2 25 1b 11 08 a2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}