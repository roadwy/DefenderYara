
rule Trojan_BAT_AgentTesla_SPS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 62 77 75 78 6e 78 63 68 75 2e 53 65 63 75 72 65 50 61 79 6c 6f 61 64 48 61 6e 64 6c 65 72 2b 3c 46 65 74 63 68 46 72 6f 6d 4e 65 74 77 6f 72 6b 41 73 79 6e 63 } //1 Bbwuxnxchu.SecurePayloadHandler+<FetchFromNetworkAsync
		$a_81_1 = {56 78 61 64 69 73 71 2e 65 78 65 } //1 Vxadisq.exe
		$a_81_2 = {64 79 6e 61 6d 69 63 5f 63 6f 64 65 2e 62 69 6e } //1 dynamic_code.bin
		$a_81_3 = {66 48 4f 66 32 79 30 77 51 5a 78 77 37 4c 53 42 77 61 2e 56 63 33 59 41 35 62 52 6a 43 42 78 39 47 4b 78 6e 72 } //1 fHOf2y0wQZxw7LSBwa.Vc3YA5bRjCBx9GKxnr
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}