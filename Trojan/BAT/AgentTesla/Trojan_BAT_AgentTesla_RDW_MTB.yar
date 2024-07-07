
rule Trojan_BAT_AgentTesla_RDW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 33 65 63 32 33 64 35 2d 61 36 30 34 2d 34 38 35 63 2d 62 66 31 31 2d 65 63 39 30 61 33 34 32 33 37 38 37 } //1 d3ec23d5-a604-485c-bf11-ec90a3423787
		$a_01_1 = {51 75 61 6e 4c 79 42 61 6e 48 61 6e 67 } //1 QuanLyBanHang
		$a_01_2 = {66 72 6d 48 65 54 68 6f 6e 67 } //1 frmHeThong
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}