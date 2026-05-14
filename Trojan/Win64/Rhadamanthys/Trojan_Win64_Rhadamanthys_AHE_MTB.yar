
rule Trojan_Win64_Rhadamanthys_AHE_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {f2 0f 59 f1 [0-08] 4d [0-0b] 41 5c [0-03] 83 e8 01 75 e4 } //30
		$a_03_1 = {48 8b 45 d8 [0-04] 48 01 d0 0f b6 10 48 8b 4d 98 48 8b 45 ?? 48 01 c8 83 f2 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}