
rule Trojan_Win32_BHO_CQ_dll{
	meta:
		description = "Trojan:Win32/BHO.CQ!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {51 76 6f 64 41 64 42 6c 6f 63 6b 65 72 } //1 QvodAdBlocker
		$a_01_1 = {5c 00 49 00 45 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //2 \IEAdBlocker.vbp
		$a_03_2 = {2f 00 2f 00 6a 00 73 00 ?? ?? 2e 00 31 00 38 00 } //1
		$a_01_3 = {6f 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 65 00 2e 00 6a 00 73 00 } //1 o.com/ie.js
		$a_01_4 = {48 3a 5c 55 c5 cc ce c4 bc fe 5c b3 cc d0 f2 d4 b4 b4 fa c2 eb 5c b3 cc d0 f2 5c c8 ed bc fe 5c b9 e3 b8 e6 be ad d3 aa cd ea d5 fb b3 cc d0 f2 b0 fc 5c 42 48 4f b2 e5 bc fe 5c 56 42 42 48 4f 2e 74 6c 62 } //1
		$a_03_5 = {46 6d 5f 69 65 5f 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 90 05 08 01 00 53 74 72 54 6f 48 65 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}