
rule Trojan_Win32_Ddkong_A{
	meta:
		description = "Trojan:Win32/Ddkong.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 \System32\svchost.exe -k netsvcs
		$a_00_1 = {25 73 20 22 25 73 22 2c 52 75 6e 64 6c 6c 33 32 43 61 6c 6c } //1 %s "%s",Rundll32Call
		$a_00_2 = {4e 65 77 43 6f 70 79 4f 75 74 4f 66 55 41 43 } //1 NewCopyOutOfUAC
		$a_00_3 = {80 34 38 c3 40 3b 46 04 72 } //1
		$a_02_4 = {ff ff 59 59 68 [0-40] 50 c6 45 ?? 4b ff 35 f0 72 00 10 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 44 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 43 c6 45 ?? 6d c6 45 ?? 64 c6 45 ?? 41 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}