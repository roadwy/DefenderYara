
rule Ransom_Win64_Knight_ZB_MTB{
	meta:
		description = "Ransom:Win64/Knight.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 66 2d 49 6e 66 2d 6b 65 79 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 65 78 65 2e 69 63 6f } //1 Inf-Inf-key.bat.cmd.com.exe.ico
		$a_01_1 = {61 74 20 2b 30 33 33 30 2b 30 34 33 30 2b 30 35 33 30 2b 30 35 34 35 2b 30 36 33 30 2b 30 38 34 35 2b 31 30 33 30 2b 31 32 34 35 2b 31 33 34 35 2d 30 39 33 30 2d 70 61 73 73 2e 6a 70 67 65 } //1 at +0330+0430+0530+0545+0630+0845+1030+1245+1345-0930-pass.jpge
		$a_01_2 = {2d 6c 6f 63 61 6c 2e 6c 6f 63 61 6c 2e 6f 6e 69 6f 6e 2f 51 75 69 65 74 } //1 -local.local.onion/Quiet
		$a_01_3 = {56 61 6c 75 65 3e 25 73 2e 6c 6f 63 6b } //1 Value>%s.lock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}