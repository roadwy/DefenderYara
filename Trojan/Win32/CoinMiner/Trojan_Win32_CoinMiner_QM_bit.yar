
rule Trojan_Win32_CoinMiner_QM_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 5c 41 44 53 4c 20 44 69 61 6c } //01 00  CurrentVersion\Policies\Explorer\Run\ADSL Dial
		$a_01_1 = {43 50 55 2e 65 78 65 20 2d 61 20 63 72 79 70 74 6f 6e 69 67 68 74 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 } //00 00  CPU.exe -a cryptonight -o stratum+tcp
	condition:
		any of ($a_*)
 
}