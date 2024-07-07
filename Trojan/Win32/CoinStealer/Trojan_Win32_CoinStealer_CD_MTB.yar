
rule Trojan_Win32_CoinStealer_CD_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 c1 2a c1 c0 c8 90 01 01 2a c1 aa 4a 0f 85 90 00 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}