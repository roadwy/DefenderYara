
rule Trojan_Linux_Turla_HA{
	meta:
		description = "Trojan:Linux/Turla.HA,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_80_0 = {2f 72 6f 6f 74 2f 2e 73 65 73 73 } ///root/.sess  2
		$a_80_1 = {2f 72 6f 6f 74 2f 2e 74 6d 70 77 61 72 65 } ///root/.tmpware  2
		$a_80_2 = {2f 72 6f 6f 74 2f 2e 68 73 70 65 72 66 64 61 74 61 } ///root/.hsperfdata  2
		$a_80_3 = {2f 72 6f 6f 74 2f 2e 78 66 64 73 68 70 31 } ///root/.xfdshp1  2
		$a_80_4 = {2f 74 6d 70 2f 2e 73 79 6e 63 2e 70 69 64 } ///tmp/.sync.pid  2
		$a_80_5 = {2f 74 6d 70 2f 2e 78 64 66 67 } ///tmp/.xdfg  2
		$a_80_6 = {54 52 45 58 5f 50 49 44 3d 25 75 } //TREX_PID=%u  1
		$a_80_7 = {52 65 6d 6f 74 65 20 56 53 20 69 73 20 65 6d 70 74 79 20 21 } //Remote VS is empty !  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=3
 
}