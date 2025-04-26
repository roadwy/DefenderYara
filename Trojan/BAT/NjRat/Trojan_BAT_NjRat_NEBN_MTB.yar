
rule Trojan_BAT_NjRat_NEBN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 26 0c 07 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 0e 04 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 25 26 03 16 03 } //10
		$a_01_1 = {64 66 67 73 67 73 66 35 36 33 36 35 33 2e 65 78 65 } //5 dfgsgsf563653.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}