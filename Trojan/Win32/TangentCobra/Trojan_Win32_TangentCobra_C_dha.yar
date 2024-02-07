
rule Trojan_Win32_TangentCobra_C_dha{
	meta:
		description = "Trojan:Win32/TangentCobra.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 61 75 74 69 6c 75 73 2d 73 65 72 76 69 63 65 2e 64 6c 6c } //01 00  nautilus-service.dll
		$a_01_1 = {6f 78 79 67 65 6e 2e 64 6c 6c } //01 00  oxygen.dll
		$a_01_2 = {63 6f 6e 66 69 67 5f 6c 69 73 74 65 6e 2e 73 79 73 74 65 6d } //01 00  config_listen.system
		$a_01_3 = {63 74 78 2e 73 79 73 74 65 6d } //01 00  ctx.system
		$a_01_4 = {33 46 44 41 33 39 39 38 2d 42 45 46 35 2d 34 32 36 44 2d 38 32 44 38 2d 31 41 37 31 46 32 39 41 44 44 43 33 } //01 00  3FDA3998-BEF5-426D-82D8-1A71F29ADDC3
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 61 63 68 65 73 5c 7b 25 73 7d 2e 32 2e 76 65 72 30 78 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 2e 64 62 } //00 00  C:\ProgramData\Microsoft\Windows\Caches\{%s}.2.ver0x0000000000000001.db
	condition:
		any of ($a_*)
 
}