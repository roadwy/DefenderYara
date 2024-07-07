
rule Trojan_Win32_CoinMiner_ABAS_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.ABAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 70 70 43 61 63 68 65 5c 78 38 36 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 C:\AppCache\x86\svchost.exe
		$a_01_1 = {2d 61 20 6d 37 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 78 63 6e 70 6f 6f 6c 2e 31 67 68 2e 63 6f 6d 3a 37 33 33 33 20 2d 75 20 43 4a 4a 6b 56 7a 6a 78 38 47 4e 74 58 34 7a 33 39 35 62 44 59 34 47 46 57 4c 36 45 68 64 66 38 6b 4a 2e 53 45 52 56 45 52 25 52 41 4e 44 4f 4d 25 20 2d 70 20 78 } //1 -a m7 -o stratum+tcp://xcnpool.1gh.com:7333 -u CJJkVzjx8GNtX4z395bDY4GFWL6Ehdf8kJ.SERVER%RANDOM% -p x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}