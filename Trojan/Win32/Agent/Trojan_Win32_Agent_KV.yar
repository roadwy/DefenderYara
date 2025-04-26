
rule Trojan_Win32_Agent_KV{
	meta:
		description = "Trojan:Win32/Agent.KV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 57 69 6e 5f 6c 61 6a 2e 69 6e 69 } //1 c:\Win_laj.ini
		$a_01_1 = {25 73 77 69 6e 64 6f 77 73 5c 78 69 6e 73 74 61 6c 6c 25 64 2e 64 6c 6c } //1 %swindows\xinstall%d.dll
		$a_01_2 = {4d 6a 6a 78 68 6a 5f 5f 42 6a 6e 6c } //1 Mjjxhj__Bjnl
		$a_01_3 = {4d 00 53 00 4e 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 47 00 75 00 61 00 72 00 64 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 MSN Security Guard Install
		$a_03_4 = {ff 33 c6 85 ?? fe ff ff 36 c6 85 ?? fe ff ff 30 c6 85 ?? fe ff ff 53 c6 85 ?? fe ff ff 61 c6 85 ?? fe ff ff 66 c6 85 ?? fe ff ff 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}