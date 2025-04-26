
rule Trojan_BAT_AgentTesla_GNX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {67 79 52 45 64 4a 4b 71 54 44 2f 63 62 6f 72 69 6e 65 77 2e 74 78 74 } //gyREdJKqTD/cborinew.txt  1
		$a_80_1 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 34 42 6d 55 6b 42 47 4e 4f 36 2f 42 41 4e 47 47 2e 74 78 74 } //transfer.sh/get/4BmUkBGNO6/BANGG.txt  1
		$a_80_2 = {4d 4b 4c 50 30 39 39 38 2e 65 78 65 } //MKLP0998.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}