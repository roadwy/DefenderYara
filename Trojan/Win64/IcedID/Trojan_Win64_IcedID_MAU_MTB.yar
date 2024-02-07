
rule Trojan_Win64_IcedID_MAU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 00 4c 89 44 24 18 89 54 24 10 3a f6 74 90 01 01 b8 01 00 00 00 83 c0 00 eb 90 01 01 48 83 c4 18 c3 90 00 } //01 00 
		$a_01_1 = {6b 66 75 61 73 67 79 64 68 75 73 61 64 6b 61 73 64 } //01 00  kfuasgydhusadkasd
		$a_01_2 = {43 74 6a 42 55 4f 48 69 69 4b 68 57 78 63 7a 50 } //00 00  CtjBUOHiiKhWxczP
	condition:
		any of ($a_*)
 
}