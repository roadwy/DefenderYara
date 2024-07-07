
rule Trojan_Win64_AbuseCommBack_FH{
	meta:
		description = "Trojan:Win64/AbuseCommBack.FH,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 00 70 00 3e 00 39 00 37 00 39 00 36 00 43 00 45 00 31 00 45 00 37 00 32 00 41 00 38 00 38 00 37 00 34 00 44 00 35 00 39 00 34 00 46 00 36 00 35 00 37 00 33 00 46 00 34 00 34 00 43 00 39 00 34 00 46 00 42 00 36 00 34 00 39 00 34 00 37 00 33 00 42 00 34 00 31 00 39 00 34 00 44 00 43 00 44 00 38 00 30 00 43 00 34 00 30 00 36 00 42 00 46 00 45 00 38 00 38 00 45 00 34 00 42 00 33 00 36 00 36 00 32 00 3c 00 2f 00 70 00 3e 00 } //1 <p>9796CE1E72A8874D594F6573F44C94FB649473B4194DCD80C406BFE88E4B3662</p>
		$a_01_1 = {39 37 39 36 43 45 31 45 37 32 41 38 38 37 34 44 35 39 34 46 36 35 37 33 46 34 34 43 39 34 46 42 36 34 39 34 37 33 42 34 31 39 34 44 43 44 38 30 43 34 30 36 42 46 45 38 38 45 34 42 33 36 36 32 00 00 00 00 00 00 00 00 } //1
		$a_01_2 = {74 61 62 6c 65 69 64 39 37 39 36 43 45 31 45 37 32 41 38 38 37 34 44 35 39 34 46 36 35 37 33 46 34 34 43 39 34 46 42 36 34 39 34 37 33 42 34 31 39 34 44 43 44 38 30 43 34 30 36 42 46 45 38 38 45 34 42 33 36 36 32 69 64 } //1 tableid9796CE1E72A8874D594F6573F44C94FB649473B4194DCD80C406BFE88E4B3662id
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}