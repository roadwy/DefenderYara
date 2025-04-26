
rule Trojan_Win32_Ursnif_KMG_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cf 2b ce 0f b6 f3 81 e9 30 5a 01 00 05 1c ba 0d 01 2b f1 89 45 00 81 ee e8 70 01 00 83 c5 04 ff 4c 24 10 a3 70 d8 52 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}