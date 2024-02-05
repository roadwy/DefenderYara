
rule Trojan_Win32_Copak_DT_MTB{
	meta:
		description = "Trojan:Win32/Copak.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {81 ea de a1 d9 83 e8 90 02 04 31 1f 47 81 ea 01 00 00 00 39 cf 75 90 00 } //05 00 
		$a_03_1 = {81 eb 01 00 00 00 e8 90 02 04 81 c3 88 ea fe 2b 31 17 21 c3 48 47 81 eb cf de 06 04 09 c3 39 cf 75 90 00 } //05 00 
		$a_03_2 = {29 f6 81 ee 28 da 95 bc e8 90 02 04 89 f6 21 f7 31 02 29 fe 29 fe 42 39 ca 75 90 00 } //05 00 
		$a_01_3 = {31 31 81 e8 aa 5c 98 ac 01 c0 81 c1 01 00 00 00 29 ff 39 d9 75 } //00 00 
	condition:
		any of ($a_*)
 
}