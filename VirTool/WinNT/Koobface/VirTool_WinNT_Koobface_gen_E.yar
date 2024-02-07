
rule VirTool_WinNT_Koobface_gen_E{
	meta:
		description = "VirTool:WinNT/Koobface.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,19 00 15 00 0c 00 00 05 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 48 00 41 00 53 00 50 00 4e 00 54 00 44 00 65 00 76 00 } //05 00  \DosDevices\HASPNTDev
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 41 00 53 00 50 00 4e 00 54 00 44 00 65 00 76 00 } //05 00  \Device\HASPNTDev
		$a_01_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 54 00 63 00 70 00 46 00 69 00 6c 00 74 00 65 00 72 00 } //05 00  \Device\TcpFilter
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 55 00 64 00 70 00 46 00 69 00 6c 00 74 00 65 00 72 00 } //05 00  \Device\UdpFilter
		$a_00_4 = {6d 61 78 69 6d 6f 2e 73 79 73 00 } //01 00 
		$a_03_5 = {ff 75 0c 83 e8 24 c6 00 0f c6 40 01 06 89 48 14 8b 4f 08 89 48 18 57 c7 40 04 02 00 00 00 89 58 08 89 58 0c 89 58 10 e8 90 01 02 00 00 8b 4d 10 8b d6 ff 15 90 00 } //05 00 
		$a_01_6 = {73 65 61 72 63 68 66 6f 72 3d 00 } //05 00 
		$a_01_7 = {2f 62 61 72 3f 00 } //05 00  戯牡?
		$a_01_8 = {5c 5c 2e 5c 48 41 53 50 4e 54 44 65 76 00 } //05 00  屜尮䅈偓呎敄v
		$a_00_9 = {76 69 72 75 73 } //05 00  virus
		$a_00_10 = {73 70 79 77 61 72 65 } //01 00  spyware
		$a_03_11 = {83 7d c8 02 0f 84 90 01 04 6a 03 58 6a 07 89 85 48 fd ff ff 89 85 4c fd ff ff 89 85 50 fd ff ff 89 85 54 fd ff ff 58 53 c7 85 00 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_WinNT_Koobface_gen_E_2{
	meta:
		description = "VirTool:WinNT/Koobface.gen!E,SIGNATURE_TYPE_PEHSTR,17 00 17 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6b 6f 36 2e 73 79 73 } //01 00  oko6.sys
		$a_01_1 = {6f 36 6b 6f 2e 73 79 73 } //01 00  o6ko.sys
		$a_01_2 = {69 6d 61 70 69 6f 6b 6f 2e 73 79 73 } //01 00  imapioko.sys
		$a_01_3 = {6d 72 78 6f 6b 6f 2e 73 79 73 } //01 00  mrxoko.sys
		$a_01_4 = {76 67 61 6f 6b 6f 2e 73 79 73 } //01 00  vgaoko.sys
		$a_01_5 = {6e 64 69 73 6f 6b 6f 2e 73 79 73 } //01 00  ndisoko.sys
		$a_01_6 = {6f 6b 6f 6d 6f 68 2e 73 79 73 } //01 00  okomoh.sys
		$a_01_7 = {68 61 73 70 73 75 78 2e 73 79 73 } //01 00  haspsux.sys
		$a_01_8 = {6d 66 6f 6b 6f 2e 73 79 73 } //01 00  mfoko.sys
		$a_01_9 = {6e 6f 6b 6f 6d 6e 74 2e 73 79 73 } //01 00  nokomnt.sys
		$a_01_10 = {6b 6c 69 66 6f 6b 6f 2e 73 79 73 } //0b 00  klifoko.sys
		$a_01_11 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 55 00 64 00 70 00 46 00 69 00 6c 00 74 00 65 00 72 00 } //0b 00  \Device\UdpFilter
		$a_01_12 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 54 00 63 00 70 00 46 00 69 00 6c 00 74 00 65 00 72 00 } //00 00  \Device\TcpFilter
	condition:
		any of ($a_*)
 
}