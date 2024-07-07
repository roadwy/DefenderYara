
rule Trojan_Win32_Seimon_gen_A{
	meta:
		description = "Trojan:Win32/Seimon.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 70 68 70 3f 6f 76 74 3d 25 43 4c 49 45 4e 54 49 44 } //1 .php?ovt=%CLIENTID
		$a_01_1 = {26 69 70 61 64 64 72 3d 25 49 50 } //1 &ipaddr=%IP
		$a_01_2 = {50 61 63 6b 65 74 53 6e 69 66 66 65 72 43 6c 61 73 73 31 } //3 PacketSnifferClass1
		$a_01_3 = {3f 65 63 3d 25 4f 56 45 52 54 55 52 45 49 44 } //1 ?ec=%OVERTUREID
		$a_01_4 = {26 70 74 3d 33 26 6d 61 78 3d 35 26 71 75 65 72 79 3d } //1 &pt=3&max=5&query=
		$a_01_5 = {68 72 65 66 3d 22 25 43 4c 49 43 4b 55 52 4c 22 20 74 61 72 67 65 74 3d 22 5f 62 6c 61 6e 6b 22 } //1 href="%CLICKURL" target="_blank"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}