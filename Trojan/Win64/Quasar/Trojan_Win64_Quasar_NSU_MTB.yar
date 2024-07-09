
rule Trojan_Win64_Quasar_NSU_MTB{
	meta:
		description = "Trojan:Win64/Quasar.NSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 bb bd 00 00 48 8b 4c 24 ?? 48 89 ca 48 c1 e1 ?? 48 bb 00 00 00 00 c0 00 00 00 48 09 d9 48 89 08 48 8b 0d 28 f3 22 00 48 89 48 ?? 48 89 05 1d f3 22 00 48 8d 42 ?? 48 85 c0 7d b6 } //5
		$a_01_1 = {6f 6e 75 78 48 } //1 onuxH
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}