
rule Trojan_BAT_WhiteSnake_RDB_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {38 64 66 30 33 34 36 31 2d 31 31 32 64 2d 34 33 38 37 2d 61 39 30 64 2d 35 32 35 64 62 33 63 64 62 66 37 35 } //1 8df03461-112d-4387-a90d-525db3cdbf75
		$a_01_1 = {5f 47 61 73 50 34 6f 46 6a 59 51 63 77 45 } //1 _GasP4oFjYQcwE
		$a_01_2 = {72 73 74 72 74 6d 67 72 2e 64 6c 6c } //1 rstrtmgr.dll
		$a_01_3 = {52 6d 53 74 61 72 74 53 65 73 73 69 6f 6e } //1 RmStartSession
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}