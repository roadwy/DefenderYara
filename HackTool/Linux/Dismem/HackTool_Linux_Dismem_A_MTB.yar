
rule HackTool_Linux_Dismem_A_MTB{
	meta:
		description = "HackTool:Linux/Dismem.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 47 72 65 70 52 65 73 75 6c 74 } //1 cmd.GrepResult
		$a_01_1 = {2f 6c 69 61 6d 67 2f 64 69 73 6d 65 6d 62 65 72 2f 70 6b 67 2f 70 72 6f 63 } //5 /liamg/dismember/pkg/proc
		$a_01_2 = {2f 6c 69 61 6d 67 2f 64 69 73 6d 65 6d 62 65 72 2f 70 6b 67 2f 73 65 63 72 65 74 73 } //5 /liamg/dismember/pkg/secrets
		$a_01_3 = {2f 6c 69 61 6d 67 2f 64 69 73 6d 65 6d 62 65 72 2f 69 6e 74 65 72 6e 61 6c 2f 63 6d 64 } //5 /liamg/dismember/internal/cmd
		$a_01_4 = {2f 6c 69 61 6d 67 2f 64 69 73 6d 65 6d 62 65 72 2f 69 6e 74 65 72 6e 61 6c 2f 70 6b 67 2f 64 65 62 75 67 } //5 /liamg/dismember/internal/pkg/debug
		$a_01_5 = {2a 70 72 6f 63 2e 44 65 76 69 63 65 } //1 *proc.Device
		$a_01_6 = {2f 6d 6d 2f 74 72 61 6e 73 70 61 72 65 6e 74 5f 68 75 67 65 70 61 67 65 2f 68 70 61 67 65 5f 70 6d 64 5f 73 69 7a 65 } //1 /mm/transparent_hugepage/hpage_pmd_size
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}