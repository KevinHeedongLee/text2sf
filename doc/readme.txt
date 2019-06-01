This is a conversion tool that reads the 'debug print' output from the ABCC
driver and exports the ABCC state changes and messages in 'Sharkfood' format.

The output format is a PCAP file which should be loaded into Wireshark to let
the Sharkfood dissector translate it to plain text.

State change printouts like...
>
> ANB_STATUS: ABP_ANB_STATE_SETUP
>
...will be converted to an 'ABCC State' entry.

Message printouts like...
>
> Msg received:
> [ MsgBuf:0x20005c78 Size:0x0002 SrcId  :0x03 DestObj:0x01
> Inst  :0x0001     Cmd :0x01   CmdExt0:0x01 CmdExt1:0x00 ]
> [ 0x03 0x04 ]
>
...will be converted to an 'ABCC Message' entry.
