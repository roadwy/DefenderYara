
rule Ransom_Win32_REntS_PA_MTB{
	meta:
		description = "Ransom:Win32/REntS.PA!MTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 4c 00 41 00 47 00 55 00 45 00 31 00 37 00 2e 00 74 00 78 00 74 00 } //01 00  PLAGUE17.txt
		$a_01_1 = {33 00 32 00 33 00 30 00 39 00 35 00 39 00 31 00 38 00 34 00 32 00 34 00 38 00 38 00 30 00 38 00 35 00 33 00 31 00 } //01 00  3230959184248808531
		$a_01_2 = {2e 00 2a 00 5c 00 2e 00 70 00 61 00 79 00 63 00 72 00 79 00 70 00 74 00 40 00 67 00 6d 00 61 00 69 00 6c 00 5f 00 63 00 6f 00 6d 00 } //01 00  .*\.paycrypt@gmail_com
		$a_01_3 = {2e 00 2a 00 5c 00 2e 00 6b 00 65 00 79 00 62 00 74 00 63 00 40 00 67 00 6d 00 61 00 69 00 6c 00 5f 00 63 00 6f 00 6d 00 } //01 00  .*\.keybtc@gmail_com
		$a_01_4 = {2e 00 2a 00 5c 00 2e 00 78 00 74 00 62 00 6c 00 } //01 00  .*\.xtbl
		$a_01_5 = {2e 00 2a 00 5c 00 2e 00 70 00 6c 00 61 00 67 00 75 00 65 00 31 00 37 00 } //01 00  .*\.plague17
		$a_01_6 = {2e 00 2a 00 5c 00 2e 00 77 00 6e 00 63 00 72 00 79 00 } //01 00  .*\.wncry
		$a_01_7 = {2e 00 2a 00 5c 00 2e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 30 00 30 00 30 00 30 00 30 00 37 00 } //01 00  .*\.crypted000007
		$a_01_8 = {2e 00 2a 00 5c 00 2e 00 77 00 61 00 6c 00 6c 00 65 00 74 00 } //01 00  .*\.wallet
		$a_01_9 = {2e 00 2a 00 40 00 66 00 6f 00 78 00 6d 00 61 00 69 00 6c 00 32 00 2e 00 2a 00 24 00 } //01 00  .*@foxmail2.*$
		$a_01_10 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 2e 00 2a 00 24 00 } //01 00  bitcoin.*$
		$a_01_11 = {2e 00 2a 00 40 00 74 00 75 00 74 00 61 00 6e 00 6f 00 74 00 61 00 2e 00 2a 00 24 00 } //01 00  .*@tutanota.*$
		$a_01_12 = {2e 00 2a 00 5c 00 2e 00 63 00 6f 00 75 00 6e 00 74 00 65 00 72 00 5f 00 64 00 75 00 70 00 } //01 00  .*\.counter_dup
		$a_01_13 = {2e 00 2a 00 5c 00 2e 00 69 00 64 00 2d 00 5b 00 30 00 2d 00 39 00 5d 00 2a 00 } //01 00  .*\.id-[0-9]*
		$a_01_14 = {2e 00 2a 00 5c 00 2e 00 62 00 61 00 63 00 6b 00 75 00 70 00 } //00 00  .*\.backup
	condition:
		any of ($a_*)
 
}