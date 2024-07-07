
rule Trojan_Win32_Trickbot_BM_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.BM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 5f 34 7a 24 50 4c 4a 44 33 40 21 69 69 30 2a 78 75 21 76 71 69 5f 32 5f 55 4b 5e 65 52 45 28 58 26 59 78 3e 78 6a 61 64 4b 48 57 24 79 4b 65 67 6a 74 3c 24 31 51 75 69 23 56 6d 35 63 79 78 } //1 0_4z$PLJD3@!ii0*xu!vqi_2_UK^eRE(X&Yx>xjadKHW$yKegjt<$1Qui#Vm5cyx
		$a_01_1 = {5c 57 69 6e 64 6f 77 73 53 44 4b 37 2d 53 61 6d 70 6c 65 73 2d 6d 61 73 74 65 72 5c 57 69 6e 64 6f 77 73 53 44 4b 37 2d 53 61 6d 70 6c 65 73 2d 6d 61 73 74 65 72 5c 63 6f 6d 5c 61 64 6d 69 6e 69 73 74 72 61 74 69 6f 6e 5c 73 70 79 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 43 6f 6d 53 70 79 2e 70 64 62 } //1 \WindowsSDK7-Samples-master\WindowsSDK7-Samples-master\com\administration\spy\Win32\Release\ComSpy.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}