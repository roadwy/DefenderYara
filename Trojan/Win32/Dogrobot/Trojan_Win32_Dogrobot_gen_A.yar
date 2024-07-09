
rule Trojan_Win32_Dogrobot_gen_A{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 30 5c 44 52 30 } //1 \Device\Harddisk0\DR0
		$a_00_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_03_2 = {b8 ff ff ff ff 0b db 74 15 8a 13 32 d0 0f b6 d2 c1 e8 08 33 04 95 ?? ?? ?? ?? 43 49 75 eb f7 d0 c3 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*5) >=5
 
}