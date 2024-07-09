
rule Trojan_Win32_Derusbi_E_dha{
	meta:
		description = "Trojan:Win32/Derusbi.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 f8 28 75 09 c7 45 ?? 5b 44 5d 00 eb 24 83 f8 2e 75 07 be ?? ?? ?? ?? eb 0a 83 f8 2d 75 13 be } //2
		$a_00_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 7a 00 69 00 70 00 74 00 6d 00 70 00 24 00 } //1 \SystemRoot\temp\ziptmp$
		$a_00_2 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 4b 00 62 00 64 00 63 00 6c 00 61 00 73 00 73 00 } //1 \Driver\Kbdclass
		$a_00_3 = {5b 49 4e 53 5d 00 5b 44 45 4c 5d 00 5b 45 4e 44 5d 00 5b 48 4f 4d 45 5d } //1 䥛华]䑛䱅]䕛䑎]䡛䵏嵅
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}