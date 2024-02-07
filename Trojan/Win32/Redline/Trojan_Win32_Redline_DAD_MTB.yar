
rule Trojan_Win32_Redline_DAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f 90 01 01 47 e2 90 00 } //01 00 
		$a_01_1 = {54 78 56 57 4c 77 7a 56 7a 6c 4f 4e 7a 44 6e 41 77 42 4b 57 4c 75 4f 72 6d 77 68 4b 77 } //01 00  TxVWLwzVzlONzDnAwBKWLuOrmwhKw
		$a_01_2 = {46 75 48 69 43 61 63 55 68 77 50 78 55 44 4c 44 74 67 66 75 76 53 59 6f 48 76 7a 4f 64 4c 54 68 76 } //01 00  FuHiCacUhwPxUDLDtgfuvSYoHvzOdLThv
		$a_01_3 = {54 54 4d 49 63 4e 6b 43 69 70 62 69 48 63 42 50 78 78 78 4e 67 69 79 7a 59 78 49 59 4b 76 4f 6b 53 } //01 00  TTMIcNkCipbiHcBPxxxNgiyzYxIYKvOkS
		$a_01_4 = {79 53 58 75 43 53 53 6d 55 42 6b 52 69 7a 61 63 52 56 64 69 68 63 6f 6e 52 6b 50 69 64 47 55 } //00 00  ySXuCSSmUBkRizacRVdihconRkPidGU
	condition:
		any of ($a_*)
 
}