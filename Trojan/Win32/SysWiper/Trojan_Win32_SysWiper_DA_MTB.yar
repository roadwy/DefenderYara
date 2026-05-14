
rule Trojan_Win32_SysWiper_DA_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 30 78 39 65 66 2f 67 6f 2d 77 69 70 65 72 2f 77 69 70 65 } //10 github.com/0x9ef/go-wiper/wipe
		$a_81_1 = {44 61 74 61 20 77 69 6c 6c 20 62 65 20 6f 76 65 72 77 72 69 74 65 64 20 77 69 74 68 20 7a 65 72 6f 65 73 } //5 Data will be overwrited with zeroes
		$a_81_2 = {64 61 74 61 20 77 69 70 69 6e 67 } //1 data wiping
		$a_81_3 = {49 4d 52 41 4e 5f 44 45 53 54 52 4f 59 45 44 5f 59 4f 55 52 5f 4f 53 5f 48 41 48 41 48 41 } //10 IMRAN_DESTROYED_YOUR_OS_HAHAHA
		$a_81_4 = {76 69 72 75 73 20 73 63 61 6e 20 66 69 6e 69 73 68 65 64 20 6c 6f 6c } //6 virus scan finished lol
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*10+(#a_81_4  & 1)*6) >=16
 
}