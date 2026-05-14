
rule Trojan_BAT_Sysn_MK_MTB{
	meta:
		description = "Trojan:BAT/Sysn.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 53 68 65 6c 6c 41 69 72 2e 54 72 61 6e 73 70 6f 72 74 2e 54 63 70 54 72 61 6e 73 70 6f 72 74 2b 3c 43 6f 6e 6e 65 63 74 41 73 79 6e 63 3e 64 } //15 PowerShellAir.Transport.TcpTransport+<ConnectAsync>d
		$a_01_1 = {50 6f 77 65 72 53 68 65 6c 6c 41 69 72 2e 54 72 61 6e 73 70 6f 72 74 2e 57 65 62 53 6f 63 6b 65 74 54 72 61 6e 73 70 6f 72 74 2b 3c 53 65 6e 64 41 73 79 6e 63 3e 64 } //10 PowerShellAir.Transport.WebSocketTransport+<SendAsync>d
		$a_01_2 = {41 50 6f 77 65 72 53 68 65 6c 6c 41 69 72 2e 54 72 61 6e 73 70 6f 72 74 2e 57 65 62 53 6f 63 6b 65 74 54 72 61 6e 73 70 6f 72 74 2b 3c 44 69 73 63 6f 6e 6e 65 63 74 41 73 79 6e 63 3e 64 } //5 APowerShellAir.Transport.WebSocketTransport+<DisconnectAsync>d
		$a_01_3 = {43 50 6f 77 65 72 53 68 65 6c 6c 41 69 72 2e 54 72 61 6e 73 70 6f 72 74 2e 57 65 62 53 6f 63 6b 65 74 54 72 61 6e 73 70 6f 72 74 2b 3c 54 72 79 52 65 63 6f 6e 6e 65 63 74 41 73 79 6e 63 3e 64 } //3 CPowerShellAir.Transport.WebSocketTransport+<TryReconnectAsync>d
		$a_01_4 = {44 50 6f 77 65 72 53 68 65 6c 6c 41 69 72 2e 54 72 61 6e 73 70 6f 72 74 2e 57 65 62 53 6f 63 6b 65 74 54 72 61 6e 73 70 6f 72 74 2b 3c 52 65 63 65 69 76 65 53 74 72 69 6e 67 41 73 79 6e 63 3e 64 } //2 DPowerShellAir.Transport.WebSocketTransport+<ReceiveStringAsync>d
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}