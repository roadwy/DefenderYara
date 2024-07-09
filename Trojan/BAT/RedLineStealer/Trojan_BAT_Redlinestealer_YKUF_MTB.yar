
rule Trojan_BAT_Redlinestealer_YKUF_MTB{
	meta:
		description = "Trojan:BAT/Redlinestealer.YKUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 25 17 59 } //1 ┇夗
		$a_03_1 = {2d 0d 26 16 2d cb 16 fe 02 0c 08 2d d9 2b 03 0b 2b f1 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}