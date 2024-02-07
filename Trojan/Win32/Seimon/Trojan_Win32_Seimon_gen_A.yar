
rule Trojan_Win32_Seimon_gen_A{
	meta:
		description = "Trojan:Win32/Seimon.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 70 68 70 3f 6f 76 74 3d 25 43 4c 49 45 4e 54 49 44 } //01 00  .php?ovt=%CLIENTID
		$a_01_1 = {26 69 70 61 64 64 72 3d 25 49 50 } //03 00  &ipaddr=%IP
		$a_01_2 = {50 61 63 6b 65 74 53 6e 69 66 66 65 72 43 6c 61 73 73 31 } //01 00  PacketSnifferClass1
		$a_01_3 = {3f 65 63 3d 25 4f 56 45 52 54 55 52 45 49 44 } //01 00  ?ec=%OVERTUREID
		$a_01_4 = {26 70 74 3d 33 26 6d 61 78 3d 35 26 71 75 65 72 79 3d } //01 00  &pt=3&max=5&query=
		$a_01_5 = {68 72 65 66 3d 22 25 43 4c 49 43 4b 55 52 4c 22 20 74 61 72 67 65 74 3d 22 5f 62 6c 61 6e 6b 22 } //00 00  href="%CLICKURL" target="_blank"
	condition:
		any of ($a_*)
 
}