
rule Backdoor_Linux_KtlvDoor_A_MTB{
	meta:
		description = "Backdoor:Linux/KtlvDoor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 6f 6f 6c 73 2f 63 6d 64 2f 61 63 63 2f 61 67 65 6e 74 5f 61 63 63 2f 68 61 6e 64 6c 65 72 2f 70 6f 72 74 73 63 61 6e 2f 74 65 6d 70 6c 61 74 65 2e 53 63 61 6e 46 75 6e 63 52 65 67 69 73 74 65 72 } //1 tools/cmd/acc/agent_acc/handler/portscan/template.ScanFuncRegister
		$a_01_1 = {2f 61 67 65 6e 74 5f 61 63 63 2f 63 6f 6e 66 2e 67 65 74 4d 61 63 68 69 6e 65 46 65 61 74 75 72 65 2e 66 75 6e 63 } //1 /agent_acc/conf.getMachineFeature.func
		$a_01_2 = {2f 61 67 65 6e 74 5f 61 63 63 2f 63 6f 6e 66 2e 55 70 64 61 74 65 48 6f 73 74 49 6e 66 6f 2e 66 75 6e 63 } //1 /agent_acc/conf.UpdateHostInfo.func
		$a_01_3 = {2f 4a 4b 6d 65 2f 67 6f 2d 6e 74 6c 6d 73 73 70 2e 43 68 61 6c 6c 65 6e 67 65 4d 73 67 2e 54 61 72 67 65 74 49 6e 66 6f } //1 /JKme/go-ntlmssp.ChallengeMsg.TargetInfo
		$a_01_4 = {2f 68 61 6e 64 6c 65 72 2f 70 6f 72 74 73 63 61 6e 2f 70 73 5f 70 6c 75 67 69 6e 73 2e 53 63 61 6e 57 65 62 2e 66 75 6e 63 } //1 /handler/portscan/ps_plugins.ScanWeb.func
		$a_01_5 = {74 6f 6f 6c 73 2f 69 6e 74 65 72 6e 61 6c 2f 75 74 69 6c 73 2f 73 68 65 6c 6c 71 75 6f 74 65 2e 67 6c 6f 62 2e 2e 66 75 6e 63 } //1 tools/internal/utils/shellquote.glob..func
		$a_01_6 = {74 6f 6f 6c 73 2f 70 6b 67 2f 63 72 79 70 74 6f 2e 58 6f 72 } //1 tools/pkg/crypto.Xor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}