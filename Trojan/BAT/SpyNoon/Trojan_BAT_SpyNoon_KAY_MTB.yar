
rule Trojan_BAT_SpyNoon_KAY_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 00 33 00 38 00 30 00 42 00 46 00 45 00 46 00 46 00 46 00 46 00 31 00 31 00 5f 00 30 00 } //3 _380BFEFFFF11_0
		$a_01_1 = {30 00 36 00 33 00 38 00 43 00 41 00 46 00 46 00 46 00 46 00 46 00 46 00 31 00 31 00 30 00 31 00 37 00 45 00 30 00 37 00 30 00 31 00 } //4 0638CAFFFFFF11017E0701
		$a_01_2 = {5f 00 5f 00 31 00 31 00 32 00 42 00 30 00 35 00 32 00 38 00 35 00 45 00 42 00 31 00 31 00 35 00 35 00 35 00 33 00 38 00 30 00 41 00 } //5 __112B05285EB11555380A
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}